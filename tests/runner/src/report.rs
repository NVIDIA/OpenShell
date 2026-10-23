// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deciding a run's result from nextest's exit status and its `JUnit` report.
//!
//! A run passes only if nextest succeeded and its report shows at least one
//! test and no failures. The runner doesn't know which tests to expect, so it
//! can't tell that a test is missing from the report.
//!
//! Adapted from the report in Evan Lezar's NVIDIA/OpenShell#4629.

use std::fmt;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Passed {
        tests: usize,
    },
    Failed {
        tests: usize,
        failed: Vec<String>,
    },
    /// The runner could not complete the run, or the results don't add up.
    Error(String),
}

impl Status {
    pub const fn is_failure(&self) -> bool {
        !matches!(self, Self::Passed { .. })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed { tests } => write!(f, "PASS: {tests} passed"),
            Self::Failed { tests, failed } => write!(
                f,
                "FAIL: {} of {tests} failed: {}",
                failed.len(),
                failed.join(", ")
            ),
            Self::Error(error) => write!(f, "ERROR: {error}"),
        }
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

/// Decide a run's status from nextest's exit status and its `JUnit` report.
pub fn decide_status(nextest_succeeded: bool, junit: Option<&str>, log: &Path) -> Status {
    let Some(xml) = junit else {
        return Status::Error(format!(
            "nextest produced no JUnit report (exit {}); see {}",
            if nextest_succeeded {
                "success"
            } else {
                "failure"
            },
            log.display()
        ));
    };
    let cases = parse_cases(xml);
    let failed: Vec<_> = cases
        .iter()
        .filter(|case| case.result == CaseResult::Failed)
        .map(|case| format!("{} {}", case.classname, case.name))
        .collect();
    let tests = cases
        .iter()
        .filter(|case| case.result != CaseResult::Skipped)
        .count();
    if !failed.is_empty() {
        Status::Failed { tests, failed }
    } else if !nextest_succeeded {
        Status::Error(format!(
            "nextest failed, but the JUnit report shows no failed test; see {}",
            log.display()
        ))
    } else if tests == 0 {
        Status::Error(format!("no test ran; see {}", log.display()))
    } else {
        Status::Passed { tests }
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const REPORT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="1" errors="0" uuid="x" timestamp="t" time="1.0">
<testsuite name="p::b" tests="3">
  <testcase name="passed" classname="p::b" time="1.0"/>
  <testcase name="failed" classname="p::b" time="1.0"><failure message="x"/></testcase>
  <testcase name="skipped" classname="p::b" time="0.0"><skipped/></testcase>
</testsuite></testsuites>"#;

    fn report(cases: &[(&str, &str)]) -> String {
        let body: String = cases
            .iter()
            .map(|(name, child)| {
                format!(
                    "<testcase name=\"{name}\" classname=\"p::b\" time=\"1\">{child}</testcase>"
                )
            })
            .collect();
        format!("<testsuites><testsuite name=\"p::b\">{body}</testsuite></testsuites>")
    }

    fn log() -> PathBuf {
        PathBuf::from("nextest.log")
    }

    #[test]
    fn parses_cases_and_their_results() {
        let results: Vec<_> = parse_cases(REPORT)
            .into_iter()
            .map(|case| (case.name, case.result))
            .collect();
        assert_eq!(
            results,
            [
                ("passed".to_string(), CaseResult::Passed),
                ("failed".to_string(), CaseResult::Failed),
                ("skipped".to_string(), CaseResult::Skipped),
            ]
        );
    }

    #[test]
    fn names_are_unescaped() {
        let cases = parse_cases(r#"<testcase name="a&amp;b" classname="p::b" time="1"/>"#);
        assert_eq!(cases[0].name, "a&b");
    }

    #[test]
    fn passes_when_nextest_succeeded_and_no_test_failed() {
        let xml = report(&[("a", ""), ("b", ""), ("c", "<skipped/>")]);
        assert_eq!(
            decide_status(true, Some(&xml), &log()),
            Status::Passed { tests: 2 }
        );
    }

    #[test]
    fn failures_are_reported_by_name() {
        assert_eq!(
            decide_status(false, Some(REPORT), &log()),
            Status::Failed {
                tests: 2,
                failed: vec!["p::b failed".to_string()],
            }
        );
    }

    #[test]
    fn a_missing_report_is_an_error() {
        assert!(matches!(
            decide_status(true, None, &log()),
            Status::Error(_)
        ));
        assert!(matches!(
            decide_status(false, None, &log()),
            Status::Error(_)
        ));
    }

    #[test]
    fn nextest_failing_without_a_failed_case_is_an_error() {
        let xml = report(&[("a", "")]);
        assert!(matches!(
            decide_status(false, Some(&xml), &log()),
            Status::Error(_)
        ));
    }

    #[test]
    fn a_run_with_no_tests_is_an_error() {
        let xml = report(&[("a", "<skipped/>")]);
        match decide_status(true, Some(&xml), &log()) {
            Status::Error(message) => assert!(message.contains("no test ran"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            decide_status(true, Some("<testsuites tests=\"0\"/>"), &log()),
            Status::Error(_)
        ));
    }

    /// A report written by the nextest version the guest installs
    /// (`ansible/playbooks/nextest.yaml`) with the runner's profile, for a
    /// suite with a passing, a failing and an `#[ignore]` test. nextest leaves
    /// the ignored test out of the report entirely.
    const NEXTEST_REPORT: &str = include_str!("../testdata/nextest-0.9.143-junit.xml");

    #[test]
    fn reads_a_real_nextest_report() {
        assert_eq!(
            decide_status(false, Some(NEXTEST_REPORT), &log()),
            Status::Failed {
                tests: 2,
                failed: vec!["sandbox::smoke fails".to_string()],
            }
        );
    }
}
