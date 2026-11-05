// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `run`: run the selected tests one at a time, each in a new process.
//!
//! The program starts itself once per test as `<name> --exact --nocapture`,
//! the same interface nextest uses, in a new process group. A test that runs
//! past its timeout gets `SIGTERM`, a grace period, then `SIGKILL`. Output is
//! shown as it comes and kept for the `JUnit` report.
//!
//! A test stopped this way does not run its cleanup: testkit tests do not
//! handle `SIGTERM` yet, so sandboxes named `test-<run id>-*` can be left
//! behind.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::capture::Capture;
use super::process::{self, Ended};
use super::{ERROR_EXIT, FAILED_EXIT, SUPERVISED_ENV, junit};
use crate::registry::{Disposition, Selection, Test};

/// libtest's exit code when a test failed.
const LIBTEST_FAILED: i32 = 101;

pub struct Options {
    pub selection: Selection,
    pub timeout: Duration,
    pub grace: Duration,
    pub junit: Option<PathBuf>,
}

/// One test's result.
pub struct TestRun<'a> {
    pub test: &'a Test,
    pub outcome: Outcome,
    /// `None` for a test that did not run.
    pub duration: Option<Duration>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    /// Ignored and not asked for.
    Skipped,
    Failed(String),
    TimedOut(String),
    /// The test could not be run.
    Error(String),
    /// Stopped because the run was interrupted.
    Interrupted,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Passed => "PASS",
            Self::Skipped => "SKIP",
            Self::Failed(_) => "FAIL",
            Self::TimedOut(_) => "TIMEOUT",
            Self::Error(_) | Self::Interrupted => "ERROR",
        }
    }

    fn message(&self) -> Option<&str> {
        match self {
            Self::Passed | Self::Skipped => None,
            Self::Failed(message) | Self::TimedOut(message) | Self::Error(message) => Some(message),
            Self::Interrupted => Some("interrupted"),
        }
    }
}

pub fn run(program: &str, exe: &Path, tests: &[Test], options: &Options) -> ExitCode {
    let selected = options.selection.apply(tests);
    let to_run = selected
        .iter()
        .filter(|(_, disposition)| *disposition == Disposition::Run)
        .count();
    if to_run == 0 {
        eprintln!("{program}: no tests to run; `{program} list` shows the tests");
        return ExitCode::from(ERROR_EXIT);
    }
    if let Err(error) = process::install_stop_handlers() {
        eprintln!("{program}: install signal handlers: {error}");
        return ExitCode::from(ERROR_EXIT);
    }
    let skipped = selected.len() - to_run;
    eprintln!(
        "{program}: running {to_run} test{} one at a time{}",
        plural(to_run),
        if skipped > 0 {
            format!(", skipping {skipped} ignored")
        } else {
            String::new()
        }
    );

    let started = Instant::now();
    let selected_count = selected.len();
    let mut runs = Vec::with_capacity(selected_count);
    let mut position = 0;
    for (test, disposition) in selected {
        // A stop signal that arrives between tests still ends the run.
        if process::stop_requested() {
            break;
        }
        if disposition == Disposition::Skip {
            runs.push(TestRun {
                test,
                outcome: Outcome::Skipped,
                duration: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
            continue;
        }
        position += 1;
        let name = test.name();
        eprintln!("==> [{position}/{to_run}] {name}");
        let run = run_one(exe, test, options);
        let elapsed = run.duration.unwrap_or_default();
        match run.outcome.message() {
            None => eprintln!("<== {} {name} ({elapsed:.1?})", run.outcome.label()),
            Some(message) => eprintln!(
                "<== {} {name} ({elapsed:.1?}): {message}",
                run.outcome.label()
            ),
        }
        runs.push(run);
    }

    let not_run = selected_count - runs.len();
    let mut status = summarize(program, &runs, not_run, started.elapsed());
    if let Some(path) = &options.junit {
        match junit::write(path, &junit::report(program, &runs)) {
            Ok(()) => eprintln!("{program}: wrote {}", path.display()),
            Err(error) => {
                eprintln!("{program}: write {}: {error}", path.display());
                status = ERROR_EXIT;
            }
        }
    }
    ExitCode::from(status)
}

fn run_one<'a>(exe: &Path, test: &'a Test, options: &Options) -> TestRun<'a> {
    let name = test.name();
    let mut command = Command::new(exe);
    command
        .args([name.as_str(), "--exact", "--nocapture"])
        .env(SUPERVISED_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if test.ignored {
        command.arg("--ignored");
    }

    let started = Instant::now();
    let mut child = match process::spawn(&mut command) {
        Ok(child) => child,
        Err(error) => {
            return TestRun {
                test,
                outcome: Outcome::Error(format!("start {}: {error}", exe.display())),
                duration: Some(started.elapsed()),
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
        }
    };
    let stdout = child
        .stdout
        .take()
        .map(|stream| Capture::start(stream, std::io::stdout()));
    let stderr = child
        .stderr
        .take()
        .map(|stream| Capture::start(stream, std::io::stderr()));
    let ended = process::wait(&mut child, options.timeout, options.grace);
    let duration = started.elapsed();
    let outcome = match ended {
        Ok(ended) => outcome(ended, options.timeout),
        Err(error) => Outcome::Error(format!("wait for the test process: {error}")),
    };
    TestRun {
        test,
        outcome,
        duration: Some(duration),
        stdout: stdout.map(Capture::finish).unwrap_or_default(),
        stderr: stderr.map(Capture::finish).unwrap_or_default(),
    }
}

fn outcome(ended: Ended, timeout: Duration) -> Outcome {
    match ended {
        Ended::Exited(status) => exited(status),
        Ended::TimedOut => Outcome::TimedOut(format!(
            "timed out after {}; stopped without cleanup",
            seconds(timeout)
        )),
        Ended::Interrupted => Outcome::Interrupted,
    }
}

fn exited(status: ExitStatus) -> Outcome {
    match status.code() {
        Some(0) => Outcome::Passed,
        Some(LIBTEST_FAILED) => Outcome::Failed("test failed".to_string()),
        Some(code) if code == i32::from(ERROR_EXIT) => {
            Outcome::Error("the test process could not run the test; see its output".to_string())
        }
        Some(code) => Outcome::Failed(format!("test process exited with code {code}")),
        None => Outcome::Failed(format!("test process ended by {status}")),
    }
}

/// Print the totals and the tests that did not pass; return the exit code:
/// 1 if a test failed, 2 if one could not run or the run was interrupted
/// before `not_run` tests.
fn summarize(program: &str, runs: &[TestRun<'_>], not_run: usize, elapsed: Duration) -> u8 {
    let count =
        |predicate: fn(&Outcome) -> bool| runs.iter().filter(|run| predicate(&run.outcome)).count();
    let passed = count(|outcome| matches!(outcome, Outcome::Passed));
    let failed = count(|outcome| matches!(outcome, Outcome::Failed(_) | Outcome::TimedOut(_)));
    let errors = count(|outcome| matches!(outcome, Outcome::Error(_) | Outcome::Interrupted));
    let skipped = count(|outcome| matches!(outcome, Outcome::Skipped));
    let mut summary = format!("{program}: {passed} passed, {failed} failed");
    if errors > 0 {
        let _ = write!(summary, ", {errors} could not run");
    }
    if skipped > 0 {
        let _ = write!(summary, ", {skipped} skipped");
    }
    let _ = write!(summary, " in {elapsed:.1?}");
    eprintln!("{summary}");
    for run in runs {
        if let Some(message) = run.outcome.message() {
            eprintln!("    {} {}: {message}", run.outcome.label(), run.test.name());
        }
    }
    if not_run > 0 {
        eprintln!(
            "{program}: interrupted; {not_run} later test{} did not run",
            plural(not_run)
        );
    }
    if errors > 0 || not_run > 0 {
        ERROR_EXIT
    } else if failed > 0 {
        FAILED_EXIT
    } else {
        0
    }
}

fn seconds(duration: Duration) -> String {
    format!("{}s", duration.as_secs_f64())
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Outcome, TestRun, summarize};
    use crate::registry::Test;
    use crate::registry::tests::test;

    const TEST: Test = test("suite::m", "t", false);

    fn runs(outcomes: Vec<Outcome>) -> Vec<TestRun<'static>> {
        outcomes
            .into_iter()
            .map(|outcome| TestRun {
                test: &TEST,
                outcome,
                duration: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn exit_code_separates_failures_from_runs_that_could_not_complete() {
        let code = |outcomes| summarize("p", &runs(outcomes), 0, Duration::ZERO);
        assert_eq!(code(vec![Outcome::Passed, Outcome::Skipped]), 0);
        assert_eq!(code(vec![Outcome::Passed, Outcome::Failed("f".into())]), 1);
        assert_eq!(code(vec![Outcome::TimedOut("t".into())]), 1);
        assert_eq!(
            code(vec![
                Outcome::Failed("f".into()),
                Outcome::Error("e".into())
            ]),
            2
        );
        assert_eq!(code(vec![Outcome::Interrupted]), 2);
        // Interrupted between tests: every test that ran passed.
        assert_eq!(
            summarize("p", &runs(vec![Outcome::Passed]), 1, Duration::ZERO),
            2
        );
    }

    #[test]
    fn exit_statuses_map_to_outcomes() {
        use std::os::unix::process::ExitStatusExt;

        use super::exited;

        let status = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        assert_eq!(exited(status(0)), Outcome::Passed);
        assert_eq!(exited(status(101)), Outcome::Failed("test failed".into()));
        assert!(matches!(exited(status(2)), Outcome::Error(_)));
        assert_eq!(
            exited(status(7)),
            Outcome::Failed("test process exited with code 7".into())
        );
        let killed = exited(std::process::ExitStatus::from_raw(libc::SIGSEGV));
        assert!(
            matches!(&killed, Outcome::Failed(message) if message.contains("signal")),
            "{killed:?}"
        );
    }
}
