// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OPENSHELL_TEST_UNSUPPORTED`: tests an environment does not support yet.
//!
//! The value is a list of `<test>=<issue>` entries separated by commas and/or
//! whitespace. `<test>` is the qualified name, the crate then the name libtest
//! shows, for example `conformance::cli::stop_start`; `<issue>` is an
//! `https://` URL. A program applies the entries for the crates it links and
//! ignores the rest, so one value can serve several programs.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::registry::Test;

/// The environment variable holding the list.
pub const ENV: &str = "OPENSHELL_TEST_UNSUPPORTED";

/// The entries that apply to one program, by qualified test name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unsupported(BTreeMap<String, String>);

impl Unsupported {
    /// Read [`ENV`] and check it against `tests`.
    pub fn from_env(tests: &[Test]) -> Result<Self, String> {
        match std::env::var(ENV) {
            Ok(value) => Self::parse(&value, tests),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{ENV} is not valid UTF-8")),
        }
    }

    /// Parse `value` and keep the entries for the crates `tests` come from.
    /// Fails on a malformed entry, or on an entry in scope that is a
    /// duplicate, names no test or an `#[ignore]`d one, or has an issue that
    /// is not an `https://` URL.
    pub fn parse(value: &str, tests: &[Test]) -> Result<Self, String> {
        let packages: BTreeSet<&str> = tests.iter().map(Test::package).collect();
        let mut entries = BTreeMap::new();
        for entry in value
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|entry| !entry.is_empty())
        {
            let (name, issue) = entry
                .split_once('=')
                .filter(|(name, issue)| !name.is_empty() && !issue.is_empty())
                .ok_or_else(|| {
                    format!("{ENV}: malformed entry {entry:?}; expected <test>=<issue url>")
                })?;
            let package = name.split_once("::").map_or(name, |(package, _)| package);
            if !packages.contains(package) {
                continue;
            }
            let Some(test) = tests.iter().find(|test| test.qualified_name() == name) else {
                return Err(format!("{ENV}: {name} is not a test in this program"));
            };
            if test.ignored {
                return Err(format!(
                    "{ENV}: {name} is already #[ignore]d; remove the entry or the attribute"
                ));
            }
            if !issue.starts_with("https://") || issue.len() == "https://".len() {
                return Err(format!(
                    "{ENV}: the issue for {name} must be an https:// URL, not {issue:?}"
                ));
            }
            if entries
                .insert(name.to_string(), issue.to_string())
                .is_some()
            {
                return Err(format!("{ENV}: {name} is listed twice"));
            }
        }
        Ok(Self(entries))
    }

    /// The issue `test` is unsupported for, if it is listed.
    pub fn issue(&self, test: &Test) -> Option<&str> {
        self.0.get(&test.qualified_name()).map(String::as_str)
    }

    /// `(qualified name, issue)` in name order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, issue)| (name.as_str(), issue.as_str()))
    }

    /// The message of a forced run of an unsupported test.
    pub fn refusal(issue: &str) -> String {
        format!("unsupported: {issue}; remove the entry from {ENV} to run it")
    }
}

#[cfg(test)]
mod tests {
    use super::Unsupported;
    use crate::registry::Test;
    use crate::registry::tests::test;

    const ISSUE: &str = "https://github.com/ai-openshell/openshell/issues/1";

    const TESTS: &[Test] = &[
        test("suite::cli", "stop", false),
        test("suite::cli", "start", false),
        test("suite::cli", "later", true),
        test("suite", "top_level", false),
    ];

    fn parse(value: &str) -> Result<Unsupported, String> {
        Unsupported::parse(value, TESTS)
    }

    fn names(unsupported: &Unsupported) -> Vec<&str> {
        unsupported.entries().map(|(name, _)| name).collect()
    }

    #[test]
    fn entries_are_separated_by_commas_and_whitespace() {
        let value = format!(
            "suite::cli::stop={ISSUE},suite::cli::start={ISSUE}\n  suite::top_level={ISSUE} ,\n"
        );
        let unsupported = parse(&value).unwrap();
        assert_eq!(
            names(&unsupported),
            ["suite::cli::start", "suite::cli::stop", "suite::top_level"]
        );
        assert_eq!(unsupported.issue(&TESTS[0]), Some(ISSUE));
        assert_eq!(unsupported.issue(&TESTS[2]), None);
        assert!(parse("").unwrap().entries().next().is_none());
        assert!(parse(" , \n").unwrap().entries().next().is_none());
    }

    #[test]
    fn an_issue_may_contain_equals_signs() {
        let unsupported = parse("suite::cli::stop=https://example.com/i?id=1").unwrap();
        assert_eq!(
            unsupported.entries().next(),
            Some(("suite::cli::stop", "https://example.com/i?id=1"))
        );
    }

    #[test]
    fn entries_for_other_packages_are_ignored() {
        // Not checked at all: unknown name, bad URL, and a duplicate.
        let value = format!(
            "other::a::b=not-a-url other::a::b={ISSUE} other::c::d={ISSUE} suite::cli::stop={ISSUE}"
        );
        assert_eq!(names(&parse(&value).unwrap()), ["suite::cli::stop"]);
    }

    #[test]
    fn rejects_bad_entries_in_scope() {
        for (value, expected) in [
            ("suite::cli::stop", "malformed"),
            ("suite::cli::stop=", "malformed"),
            ("=https://x", "malformed"),
            ("other::a", "malformed"),
            ("suite::cli::nope=https://x/1", "is not a test"),
            ("suite::stop=https://x/1", "is not a test"),
            ("suite::cli::later=https://x/1", "already #[ignore]d"),
            ("suite::cli::stop=http://x/1", "must be an https:// URL"),
            ("suite::cli::stop=https://", "must be an https:// URL"),
            ("suite::cli::stop=#12", "must be an https:// URL"),
        ] {
            let error = parse(value).unwrap_err();
            assert!(error.contains(expected), "{value}: {error}");
        }
        let twice = format!("suite::cli::stop={ISSUE} suite::cli::stop={ISSUE}");
        assert!(parse(&twice).unwrap_err().contains("listed twice"));
        // A malformed entry fails even with another package's prefix.
        assert!(parse("other::a").is_err());
    }
}
