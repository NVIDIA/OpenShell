// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Job outcomes and the run summary.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The outcome of one family in one environment.
#[derive(Debug)]
pub struct Outcome {
    pub environment: String,
    pub family: String,
    pub status: Status,
    /// Tests excluded because the environment lacks a capability.
    pub unsupported_tests: usize,
    /// Tests a waiver skips in this environment.
    pub waived_tests: usize,
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
    /// Every selected test needs a capability the environment lacks.
    NothingToRun,
    /// The runner could not complete the job.
    Error(String),
}

impl Status {
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::Error(_))
    }
}

/// Test and failure counts from a `JUnit` report's root element.
pub fn junit_counts(xml: &str) -> Option<(u32, u32)> {
    let start = xml.find("<testsuites")?;
    let end = start + xml[start..].find('>')?;
    let root = &xml[start..end];
    let attr = |name: &str| -> Option<u32> {
        let key = format!(" {name}=\"");
        let value_start = root.find(&key)? + key.len();
        let value_end = value_start + root[value_start..].find('"')?;
        root[value_start..value_end].parse().ok()
    };
    let tests = attr("tests")?;
    let failures = attr("failures").unwrap_or(0) + attr("errors").unwrap_or(0);
    Some((tests, failures))
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
            Status::NothingToRun => {
                "UNSUPPORTED every selected test needs a missing capability".to_string()
            }
            Status::Error(error) => format!("ERROR       {error}"),
        };
        let mut excluded = Vec::new();
        if outcome.unsupported_tests > 0 {
            excluded.push(format!("{} tests unsupported", outcome.unsupported_tests));
        }
        if outcome.waived_tests > 0 {
            excluded.push(format!("{} waived", outcome.waived_tests));
        }
        let unsupported = if excluded.is_empty() {
            String::new()
        } else {
            format!(" ({})", excluded.join(", "))
        };
        let _ = writeln!(
            out,
            "  {} / {}: {status}{unsupported}",
            outcome.environment, outcome.family
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_junit_counts() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="1" errors="1" uuid="x" timestamp="t" time="1.0">
<testsuite name="a" tests="3"></testsuite></testsuites>"#;
        assert_eq!(junit_counts(xml), Some((3, 2)));
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
    fn missing_root_has_no_counts() {
        assert_eq!(junit_counts("<testsuite tests=\"1\"/>"), None);
    }

    #[test]
    fn summarizes_outcomes() {
        let text = summary(&[
            Outcome {
                environment: "env-a".to_string(),
                family: "conformance".to_string(),
                status: Status::Passed { tests: 2 },
                unsupported_tests: 1,
                waived_tests: 1,
            },
            Outcome {
                environment: "env-b".to_string(),
                family: "conformance".to_string(),
                status: Status::Unsupported("arch".to_string()),
                unsupported_tests: 0,
                waived_tests: 0,
            },
        ]);
        assert!(
            text.contains(
                "env-a / conformance: PASS        2 passed (1 tests unsupported, 1 waived)"
            ),
            "{text}"
        );
        assert!(
            text.contains("env-b / conformance: UNSUPPORTED arch"),
            "{text}"
        );
    }
}
