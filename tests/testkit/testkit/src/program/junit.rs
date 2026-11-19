// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `JUnit` report of a run.
//!
//! One `<testsuite>` per family. Each `<testcase>` is named by the test name,
//! with the module path as its class name and the description and family as
//! properties.

use std::collections::BTreeMap;
use std::path::Path;

use quick_junit::{NonSuccessKind, Property, Report, TestCase, TestCaseStatus, TestSuite};

use super::supervisor::{Outcome, TestRun};

pub fn report(program: &str, runs: &[TestRun<'_>]) -> Report {
    let mut suites: BTreeMap<&str, TestSuite> = BTreeMap::new();
    for run in runs {
        let family = run.test.family();
        suites
            .entry(family)
            .or_insert_with(|| TestSuite::new(family))
            .add_test_case(test_case(run));
    }
    let mut report = Report::new(program);
    report.add_test_suites(suites.into_values());
    report
}

fn test_case(run: &TestRun<'_>) -> TestCase {
    let status = match &run.outcome {
        Outcome::Passed => TestCaseStatus::success(),
        Outcome::Skipped => {
            let mut status = TestCaseStatus::skipped();
            status.set_message(match run.test.ignore_reason {
                Some(reason) => format!("ignored: {reason}"),
                None => "ignored".to_string(),
            });
            status
        }
        Outcome::Failed(message) => non_success(NonSuccessKind::Failure, "failure", message),
        Outcome::TimedOut(message) => non_success(NonSuccessKind::Failure, "timeout", message),
        Outcome::Error(message) => non_success(NonSuccessKind::Error, "error", message),
        Outcome::Interrupted => non_success(NonSuccessKind::Error, "interrupted", "interrupted"),
    };
    let mut case = TestCase::new(run.test.name(), status);
    case.set_classname(run.test.module_path)
        .add_property(Property::new("family", run.test.family()))
        .add_property(Property::new("description", run.test.info.description));
    if let Some(duration) = run.duration {
        case.set_time(duration);
    }
    if !run.stdout.is_empty() {
        case.set_system_out_lossy(&run.stdout);
    }
    if !run.stderr.is_empty() {
        case.set_system_err_lossy(&run.stderr);
    }
    case
}

fn non_success(kind: NonSuccessKind, ty: &str, message: &str) -> TestCaseStatus {
    let mut status = TestCaseStatus::non_success(kind);
    status.set_type(ty).set_message(message);
    status
}

pub fn write(path: &Path, report: &Report) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let xml = report.to_string().map_err(std::io::Error::other)?;
    std::fs::write(path, xml)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::report;
    use crate::program::supervisor::{Outcome, TestRun};
    use crate::registry::Test;
    use crate::registry::tests::test;

    const PASSED: Test = test("sandbox::smoke", "create_exec_delete", false);
    const FAILED: Test = test("sandbox::lifecycle", "stop_start", false);
    const SKIPPED: Test = Test {
        ignore_reason: Some("https://github.com/NVIDIA/OpenShell/issues/1"),
        ..test("sandbox::lifecycle", "later", true)
    };

    #[test]
    fn reports_every_outcome() {
        let run = |test, outcome, duration| TestRun {
            test,
            outcome,
            duration,
            stdout: b"out\n".to_vec(),
            stderr: Vec::new(),
        };
        let runs = [
            run(&PASSED, Outcome::Passed, Some(Duration::from_millis(1500))),
            run(
                &FAILED,
                Outcome::TimedOut("timed out after 1s".into()),
                Some(Duration::from_secs(1)),
            ),
            run(&SKIPPED, Outcome::Skipped, None),
        ];
        let xml = report("openshell-conformance", &runs).to_string().unwrap();
        for expected in [
            r#"<testsuites name="openshell-conformance" tests="3" skipped="1" failures="1" errors="0">"#,
            r#"<testsuite name="conformance" tests="3" skipped="1" errors="0" failures="1">"#,
            r#"<testcase name="smoke::create_exec_delete" classname="sandbox::smoke" time="1.500">"#,
            r#"<property name="family" value="conformance"/>"#,
            r#"<property name="description" value="A test."/>"#,
            r#"<failure message="timed out after 1s" type="timeout"/>"#,
            r#"<skipped message="ignored: https://github.com/NVIDIA/OpenShell/issues/1"/>"#,
            "<system-out>out\n</system-out>",
        ] {
            assert!(xml.contains(expected), "missing {expected} in\n{xml}");
        }
    }
}
