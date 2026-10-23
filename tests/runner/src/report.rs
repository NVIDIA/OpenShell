// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Job outcomes, `JUnit` result checking, and the run summary.
//!
//! The `JUnit` check is what keeps a lane honest: a job passes only if its
//! report has a passing case for every test the runner selected. A test that
//! is missing from the report, skipped, or not expected fails the job, so
//! dropping a test (a bad filter, a renamed function, a crashed binary)
//! cannot pass silently.
//!
//! Adapted from the report in Evan Lezar's NVIDIA/OpenShell#4629.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// The outcome of one family in one environment.
#[derive(Debug)]
pub struct Outcome {
    pub environment: String,
    pub family: String,
    pub status: Status,
}

#[derive(Debug)]
pub enum Status {
    Passed {
        tests: u32,
    },
    Failed {
        tests: u32,
        failures: u32,
    },
    /// The environment can't be provisioned on this host.
    Unsupported(String),
    /// The selected suites have no tests.
    NothingToRun,
    /// The runner could not complete the job, or the results did not match
    /// what was expected.
    Error(String),
}

impl Status {
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::Error(_))
    }
}

/// How one test case ended, from a `JUnit` report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseResult {
    Passed,
    Failed,
    Skipped,
}

/// One test case in a `JUnit` report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub classname: String,
    pub name: String,
    pub result: CaseResult,
}

/// A `JUnit` report compared with the tests that were expected.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verification {
    /// Test cases in the report.
    pub tests: u32,
    /// Expected tests that failed.
    pub failed: Vec<String>,
    /// Expected tests with no passing or failing case: absent from the
    /// report, or skipped.
    pub missing: Vec<String>,
    /// Cases in the report that nothing selected.
    pub unexpected: Vec<String>,
}

impl Verification {
    /// Whether the report has a passing case for exactly the expected tests.
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty() && self.missing.is_empty() && self.unexpected.is_empty()
    }

    /// The mismatch between the report and the selection, if any, as a
    /// message. Failures are not a mismatch: they are the tests' own result.
    pub fn mismatch(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.missing.is_empty() {
            parts.push(format!(
                "expected tests missing from the report or skipped: {}",
                self.missing.join(", ")
            ));
        }
        if !self.unexpected.is_empty() {
            parts.push(format!(
                "tests in the report that were not selected: {}",
                self.unexpected.join(", ")
            ));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// The test cases in a `JUnit` report written by nextest.
pub fn parse_cases(xml: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<testcase ") {
        let Some(len) = rest[start..].find('>') else {
            break;
        };
        let tag_end = start + len;
        let tag = &rest[start..tag_end];
        let (body, next) = if tag.ends_with('/') {
            ("", tag_end + 1)
        } else {
            let close = rest[tag_end..]
                .find("</testcase>")
                .map_or(rest.len(), |offset| tag_end + offset);
            (&rest[tag_end + 1..close], close)
        };
        if let (Some(classname), Some(name)) = (attr(tag, "classname"), attr(tag, "name")) {
            let result = if body.contains("<failure") || body.contains("<error") {
                CaseResult::Failed
            } else if body.contains("<skipped") {
                CaseResult::Skipped
            } else {
                CaseResult::Passed
            };
            cases.push(Case {
                classname: unescape(classname),
                name: unescape(name),
                result,
            });
        }
        rest = &rest[next.min(rest.len())..];
    }
    cases
}

/// Compare a `JUnit` report with the tests that had to run, as nextest
/// `(classname, name)` pairs.
pub fn verify_junit(xml: &str, expected: &BTreeSet<(String, String)>) -> Verification {
    let cases = parse_cases(xml);
    let mut verification = Verification {
        tests: u32::try_from(cases.len()).unwrap_or(u32::MAX),
        ..Verification::default()
    };
    let label = |classname: &str, name: &str| format!("{classname} {name}");

    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for case in &cases {
        let key = (case.classname.as_str(), case.name.as_str());
        seen.insert(key);
        let is_expected = expected.contains(&(case.classname.clone(), case.name.clone()));
        if !is_expected {
            // A skipped case that was never expected is an `#[ignore]` test:
            // nextest lists it, and it did not run, so it is not a problem.
            if case.result != CaseResult::Skipped {
                verification
                    .unexpected
                    .push(label(&case.classname, &case.name));
            }
            continue;
        }
        match case.result {
            CaseResult::Passed => {}
            CaseResult::Failed => verification.failed.push(label(&case.classname, &case.name)),
            CaseResult::Skipped => verification
                .missing
                .push(label(&case.classname, &case.name)),
        }
    }
    for (classname, name) in expected {
        if !seen.contains(&(classname.as_str(), name.as_str())) {
            verification.missing.push(label(classname, name));
        }
    }
    verification
}

/// The `JUnit` property that carries a test's stable ID.
pub const TEST_ID_PROPERTY: &str = "test_id";

/// Add each test's stable ID to its `<testcase>` as a property.
///
/// `ids` maps a nextest `(classname, name)` pair (`<package>::<binary>`, test
/// name) to the test's ID. Test cases not in `ids` are left unchanged. The
/// property is the test case's first child, where pytest's
/// `record_property` puts it.
pub fn annotate_junit(xml: &str, ids: &BTreeMap<(String, String), String>) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<testcase ") {
        let Some(len) = rest[start..].find('>') else {
            break;
        };
        let end = start + len;
        let tag = &rest[start..end];
        out.push_str(&rest[..start]);
        let key = attr(tag, "classname").zip(attr(tag, "name"));
        match key.and_then(|(classname, name)| ids.get(&(classname.to_string(), name.to_string())))
        {
            Some(id) => {
                let properties = format!(
                    "<properties><property name=\"{TEST_ID_PROPERTY}\" value=\"{id}\"/></properties>"
                );
                match tag.strip_suffix('/') {
                    Some(open) => {
                        let _ = write!(out, "{open}>{properties}</testcase>");
                    }
                    None => {
                        let _ = write!(out, "{tag}>{properties}");
                    }
                }
            }
            None => {
                out.push_str(tag);
                out.push('>');
            }
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// An attribute value from a start tag. nextest escapes `"` in values.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = start + tag[start..].find('"')?;
    Some(&tag[start..end])
}

fn unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// A human-readable summary of every outcome.
pub fn summary(outcomes: &[Outcome]) -> String {
    let mut out = String::from("\nSummary\n");
    for outcome in outcomes {
        let status = match &outcome.status {
            Status::Passed { tests } => format!("PASS        {tests} passed"),
            Status::Failed { tests, failures } => {
                format!("FAIL        {failures} of {tests} failed")
            }
            Status::Unsupported(reason) => format!("UNSUPPORTED {reason}"),
            Status::NothingToRun => "UNSUPPORTED the selected suites have no tests".to_string(),
            Status::Error(error) => format!("ERROR       {error}"),
        };
        let _ = writeln!(
            out,
            "  {} / {}: {status}",
            outcome.environment, outcome.family
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1" errors="0" uuid="x" timestamp="t" time="1.0">
<testsuite name="p::b" tests="4">
  <testcase name="passed" classname="p::b" time="1.0"/>
  <testcase name="failed" classname="p::b" time="1.0"><failure message="x"/></testcase>
  <testcase name="skipped" classname="p::b" time="0.0"><skipped/></testcase>
  <testcase name="extra" classname="p::b" time="1.0"><system-out>ok</system-out></testcase>
</testsuite></testsuites>"#;

    fn expected(names: &[&str]) -> BTreeSet<(String, String)> {
        names
            .iter()
            .map(|name| ("p::b".to_string(), (*name).to_string()))
            .collect()
    }

    #[test]
    fn parses_cases_and_their_results() {
        let cases = parse_cases(REPORT);
        let results: Vec<_> = cases
            .iter()
            .map(|case| (case.name.as_str(), case.result))
            .collect();
        assert_eq!(
            results,
            [
                ("passed", CaseResult::Passed),
                ("failed", CaseResult::Failed),
                ("skipped", CaseResult::Skipped),
                ("extra", CaseResult::Passed),
            ]
        );
        assert!(cases.iter().all(|case| case.classname == "p::b"));
    }

    #[test]
    fn a_report_with_exactly_the_expected_passing_tests_is_clean() {
        let verification = verify_junit(REPORT, &expected(&["passed", "extra"]));
        // `failed` was not expected, so it is unexpected. `skipped` was not
        // expected either, which is what an `#[ignore]` test looks like, so it
        // is not reported.
        assert_eq!(verification.unexpected.len(), 1, "{verification:?}");
        assert!(
            verification.unexpected[0].ends_with("failed"),
            "{verification:?}"
        );
        let clean = verify_junit(
            r#"<testsuite><testcase name="a" classname="p::b" time="1"/></testsuite>"#,
            &expected(&["a"]),
        );
        assert!(clean.is_clean(), "{clean:?}");
        assert_eq!(clean.tests, 1);
        assert_eq!(clean.mismatch(), None);
    }

    #[test]
    fn a_missing_test_is_a_mismatch() {
        let verification = verify_junit(REPORT, &expected(&["passed", "extra", "gone"]));
        assert_eq!(verification.missing, ["p::b gone"]);
        let message = verification.mismatch().unwrap();
        assert!(message.contains("missing from the report or skipped: p::b gone"));
    }

    #[test]
    fn a_skipped_test_counts_as_missing() {
        let verification = verify_junit(REPORT, &expected(&["passed", "skipped"]));
        assert_eq!(verification.missing, ["p::b skipped"]);
    }

    #[test]
    fn a_failed_test_is_a_failure_not_a_mismatch() {
        let verification = verify_junit(REPORT, &expected(&["passed", "failed"]));
        assert_eq!(verification.failed, ["p::b failed"]);
        assert!(verification.missing.is_empty());
        // `skipped` and `extra` were not expected.
        assert!(verification.mismatch().unwrap().contains("not selected"));
    }

    #[test]
    fn an_empty_report_misses_every_expected_test() {
        let verification = verify_junit("<testsuites tests=\"0\"/>", &expected(&["a", "b"]));
        assert_eq!(verification.tests, 0);
        assert_eq!(verification.missing.len(), 2);
    }

    #[test]
    fn names_are_unescaped() {
        let cases = parse_cases(r#"<testcase name="a&amp;b" classname="p::b" time="1"/>"#);
        assert_eq!(cases[0].name, "a&b");
    }

    #[test]
    fn annotates_test_cases_with_ids() {
        let xml = r#"<testsuite name="p::b" tests="3">
        <testcase name="passed" classname="p::b" time="1.0"/>
        <testcase name="failed" classname="p::b" time="1.0"><failure message="x"/></testcase>
        <testcase name="unknown" classname="p::b" time="1.0"/>
    </testsuite>"#;
        let ids = BTreeMap::from([
            (
                ("p::b".to_string(), "passed".to_string()),
                "t-00000001".to_string(),
            ),
            (
                ("p::b".to_string(), "failed".to_string()),
                "t-00000002".to_string(),
            ),
        ]);
        let out = annotate_junit(xml, &ids);
        assert!(out.contains(
            r#"<testcase name="passed" classname="p::b" time="1.0"><properties><property name="test_id" value="t-00000001"/></properties></testcase>"#
        ), "{out}");
        assert!(out.contains(
            r#"<testcase name="failed" classname="p::b" time="1.0"><properties><property name="test_id" value="t-00000002"/></properties><failure message="x"/></testcase>"#
        ), "{out}");
        assert!(
            out.contains(r#"<testcase name="unknown" classname="p::b" time="1.0"/>"#),
            "{out}"
        );
        assert!(out.ends_with("</testsuite>"), "{out}");
    }

    #[test]
    fn annotated_reports_still_verify() {
        let xml = r#"<testcase name="a" classname="p::b" time="1.0"/>"#;
        let ids = BTreeMap::from([(
            ("p::b".to_string(), "a".to_string()),
            "t-00000001".to_string(),
        )]);
        let annotated = annotate_junit(xml, &ids);
        assert!(verify_junit(&annotated, &expected(&["a"])).is_clean());
    }

    #[test]
    fn summarizes_outcomes() {
        let text = summary(&[
            Outcome {
                environment: "env-a".to_string(),
                family: "conformance".to_string(),
                status: Status::Passed { tests: 2 },
            },
            Outcome {
                environment: "env-b".to_string(),
                family: "conformance".to_string(),
                status: Status::Unsupported("arch".to_string()),
            },
        ]);
        assert!(
            text.contains("env-a / conformance: PASS        2 passed"),
            "{text}"
        );
        assert!(
            text.contains("env-b / conformance: UNSUPPORTED arch"),
            "{text}"
        );
    }

    /// A report written by the nextest version the guest installs
    /// (`ansible/playbooks/nextest.yaml`) with the runner's profile, for a
    /// suite with a passing, a failing and an `#[ignore]` test. nextest leaves
    /// the ignored test out of the report entirely.
    const NEXTEST_REPORT: &str = include_str!("../testdata/nextest-0.9.143-junit.xml");

    #[test]
    fn verifies_a_real_nextest_report() {
        let expected: BTreeSet<_> = [
            ("sandbox::smoke", "create_exec_delete"),
            ("sandbox::smoke", "fails"),
        ]
        .into_iter()
        .map(|(classname, name)| (classname.to_string(), name.to_string()))
        .collect();
        let verification = verify_junit(NEXTEST_REPORT, &expected);
        assert_eq!(verification.tests, 2);
        assert_eq!(verification.failed, ["sandbox::smoke fails"]);
        assert!(verification.missing.is_empty(), "{verification:?}");
        assert!(verification.unexpected.is_empty(), "{verification:?}");
    }

    #[test]
    fn annotates_a_real_nextest_report() {
        let ids = BTreeMap::from([(
            ("sandbox::smoke".to_string(), "fails".to_string()),
            "t-0123abcd".to_string(),
        )]);
        let annotated = annotate_junit(NEXTEST_REPORT, &ids);
        assert!(
            annotated.contains(
                r#"classname="sandbox::smoke" timestamp="2026-10-22T20:54:54.894-07:00" time="0.026"><properties><property name="test_id" value="t-0123abcd"/></properties>"#
            ),
            "{annotated}"
        );
        // Annotating doesn't change what the report says.
        assert_eq!(parse_cases(&annotated), parse_cases(NEXTEST_REPORT));
    }
}
