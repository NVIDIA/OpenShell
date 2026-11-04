// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `testkit::main()`: a test program anyone can run against their gateway.
//!
//! A program is a binary whose `main` calls [`main`], linked with the crates
//! holding its `#[testkit::test]`s:
//!
//! ```ignore
//! fn main() -> std::process::ExitCode {
//!     testkit::main()
//! }
//! ```
//!
//! It has three subcommands:
//!
//! - `list [FILTER]...` prints each test's name and description.
//! - `ready [--timeout SECS]` waits for the gateway, as `testkit-ready` does.
//! - `run [FILTER]...` runs tests one at a time, each in its own process with
//!   a timeout, and can write a `JUnit` report. Unix only.
//!
//! Any other arguments are libtest's, so the program also works as a
//! `harness = false` test target under `cargo test` and nextest: it answers
//! `--list --format terse`, `--ignored`, and `<name> --exact --nocapture`.
//! In that mode tests run in the program's own process, one at a time unless
//! `--test-threads` says otherwise.

#[cfg(unix)]
mod capture;
#[cfg(unix)]
mod junit;
#[cfg(unix)]
mod process;
#[cfg(unix)]
mod supervisor;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

use crate::registry::{RESERVED_NAMES, Selection, TESTS, Test, validate};

/// Exit code when a test failed.
const FAILED_EXIT: u8 = 1;
/// Exit code when tests could not run, including usage errors.
const ERROR_EXIT: u8 = 2;
/// Set by `run` for the test processes it starts.
const SUPERVISED_ENV: &str = "TESTKIT_SUPERVISED";

/// Run the program: the subcommands, or libtest's interface.
pub fn main() -> ExitCode {
    main_with(&TESTS)
}

/// [`main`] over `tests` instead of every registered test.
#[doc(hidden)]
pub fn main_with(tests: &'static [Test]) -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let program = program_name(&args);
    // A suite crate that the program never names is not linked, and its
    // tests are silently missing. Fail instead of passing with nothing.
    if tests.is_empty() {
        eprintln!(
            "{program}: no tests are linked into this program; it must name each suite crate \
             it runs, for example with `use <suite> as _;`"
        );
        return ExitCode::from(ERROR_EXIT);
    }
    if let Err(error) = validate(tests) {
        eprintln!("{program}: {error}");
        return ExitCode::from(ERROR_EXIT);
    }
    let first = args.get(1).and_then(|arg| arg.to_str());
    if first.is_some_and(|arg| RESERVED_NAMES.contains(&arg) || arg == "-h" || arg == "--help") {
        let cli = match Cli::try_parse_from(&args) {
            Ok(cli) => cli,
            Err(error) => {
                let _ = error.print();
                return ExitCode::from(if error.use_stderr() { ERROR_EXIT } else { 0 });
            }
        };
        command(&program, tests, cli.command)
    } else {
        libtest(tests, args)
    }
}

#[derive(Parser)]
#[command(
    about = "Run OpenShell tests against a gateway",
    after_help = "The gateway is the one the openshell CLI selects: OPENSHELL_GATEWAY_ENDPOINT, \
                  OPENSHELL_GATEWAY, or the active gateway. OPENSHELL_WORKSPACE selects the \
                  workspace and OPENSHELL_BIN the CLI. Only plaintext and mTLS gateways are \
                  supported.\n\nWithout a subcommand the program takes libtest's arguments, \
                  as under cargo test and nextest."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print each test's name and description, including ignored tests.
    List {
        /// Show tests whose name contains any of these (all if none).
        filters: Vec<String>,
    },
    /// Wait until the gateway is healthy and the CLI reaches it. Exits 2 if
    /// it is not ready in time.
    Ready {
        /// How long to wait, in seconds.
        #[arg(long, default_value = "60", value_name = "SECS", value_parser = seconds)]
        timeout: Duration,
    },
    /// Run tests one at a time, each in its own process. Exits 1 if a test
    /// failed and 2 if tests could not run.
    Run {
        /// Run tests whose name contains any of these (all if none).
        filters: Vec<String>,
        /// Run ignored tests too.
        #[arg(long)]
        include_ignored: bool,
        /// Stop a test that runs longer than this, in seconds. Longer than
        /// testkit's own step timeouts, so those report first.
        #[arg(long, default_value = "900", value_name = "SECS", value_parser = seconds)]
        timeout: Duration,
        /// How long a stopped test has between SIGTERM and SIGKILL, in seconds.
        #[arg(long, default_value = "10", value_name = "SECS", value_parser = seconds)]
        grace: Duration,
        /// Write a JUnit report here.
        #[arg(long, value_name = "PATH")]
        junit: Option<PathBuf>,
    },
}

/// A positive, finite number of seconds.
fn seconds(value: &str) -> Result<Duration, String> {
    let seconds: f64 = value
        .parse()
        .map_err(|_| format!("{value:?} is not a number"))?;
    Duration::try_from_secs_f64(seconds)
        .ok()
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("{value:?} is not a positive number of seconds"))
}

fn command(program: &str, tests: &'static [Test], command: Command) -> ExitCode {
    match command {
        Command::List { filters } => {
            list(tests, filters);
            ExitCode::SUCCESS
        }
        Command::Ready { timeout } => ready(program, timeout),
        Command::Run {
            filters,
            include_ignored,
            timeout,
            grace,
            junit,
        } => run(
            program,
            tests,
            Selection {
                filters,
                include_ignored,
            },
            timeout,
            grace,
            junit,
        ),
    }
}

#[cfg(unix)]
fn run(
    program: &str,
    tests: &'static [Test],
    selection: Selection,
    timeout: Duration,
    grace: Duration,
    junit: Option<PathBuf>,
) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("{program}: find this program's path: {error}");
            return ExitCode::from(ERROR_EXIT);
        }
    };
    let options = supervisor::Options {
        selection,
        timeout,
        grace,
        junit,
    };
    supervisor::run(program, &exe, tests, &options)
}

#[cfg(not(unix))]
fn run(
    program: &str,
    _tests: &'static [Test],
    _selection: Selection,
    _timeout: Duration,
    _grace: Duration,
    _junit: Option<PathBuf>,
) -> ExitCode {
    eprintln!(
        "{program}: `run` is only supported on Unix; run the tests with cargo test or nextest"
    );
    ExitCode::from(ERROR_EXIT)
}

/// One line per test: name and description, in aligned columns.
/// An ignored test's description ends with `[ignored]` or its reason.
fn list(tests: &[Test], filters: Vec<String>) {
    let selection = Selection {
        filters,
        include_ignored: true,
    };
    let rows: Vec<_> = selection
        .apply(tests)
        .into_iter()
        .map(|(test, _)| (test.name(), describe(test)))
        .collect();
    let name_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(0);
    for (name, description) in rows {
        println!("{name:name_width$}  {description}");
    }
}

fn describe(test: &Test) -> String {
    let description = test.info.description;
    match (test.ignored, test.ignore_reason) {
        (false, _) => description.to_string(),
        (true, None) => format!("{description} [ignored]"),
        (true, Some(reason)) => format!("{description} [ignored: {reason}]"),
    }
}

fn ready(program: &str, timeout: Duration) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("{program}: start the async runtime: {error}");
            return ExitCode::from(ERROR_EXIT);
        }
    };
    // A gateway that is not ready means the tests cannot run.
    if runtime.block_on(crate::ready::check(program, timeout)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(ERROR_EXIT)
    }
}

/// libtest's interface, for `cargo test` and nextest, and for `run`'s test
/// processes.
fn libtest(tests: &'static [Test], args: Vec<OsString>) -> ExitCode {
    let mut args = libtest_mimic::Arguments::from_iter(args);
    // Tests share one gateway; run them one at a time unless asked otherwise.
    if args.test_threads.is_none() {
        args.test_threads = Some(1);
    }
    let mut tests: Vec<&'static Test> = tests.iter().collect();
    tests.sort_by_cached_key(|test| test.name());
    let trials = tests
        .into_iter()
        .map(|test| {
            libtest_mimic::Trial::test(test.name(), move || {
                run_in_process(test);
                Ok(())
            })
            .with_ignored_flag(test.ignored)
        })
        .collect();
    let conclusion = libtest_mimic::run(&args, trials);
    // `run` starts this process for exactly one test. Running none would
    // look like a pass.
    if std::env::var_os(SUPERVISED_ENV).is_some()
        && !args.list
        && conclusion.num_passed + conclusion.num_failed != 1
    {
        eprintln!(
            "testkit: expected to run exactly one test, ran {}",
            conclusion.num_passed + conclusion.num_failed
        );
        return ExitCode::from(ERROR_EXIT);
    }
    conclusion.exit_code()
}

/// Run one test on a fresh current-thread runtime, as `#[tokio::test]` does.
/// Panics to fail it.
fn run_in_process(test: &Test) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("start the async runtime")
        .block_on((test.run)());
}

fn program_name(args: &[OsString]) -> String {
    args.first()
        .map(PathBuf::from)
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "testkit".to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn cli_is_consistent() {
        <Cli as clap::CommandFactory>::command().debug_assert();
    }

    #[test]
    fn run_parses_selection_and_limits() {
        let cli = Cli::try_parse_from([
            "p",
            "run",
            "smoke",
            "life",
            "--include-ignored",
            "--timeout",
            "1.5",
            "--junit",
            "out/junit.xml",
        ])
        .unwrap();
        let Command::Run {
            filters,
            include_ignored,
            timeout,
            grace,
            junit,
        } = cli.command
        else {
            panic!("not run");
        };
        assert_eq!(filters, ["smoke", "life"]);
        assert!(include_ignored);
        assert_eq!(timeout, Duration::from_millis(1500));
        assert_eq!(grace, Duration::from_secs(10));
        assert_eq!(junit.unwrap().to_str(), Some("out/junit.xml"));

        let Command::Ready { timeout } = Cli::try_parse_from(["p", "ready"]).unwrap().command
        else {
            panic!("not ready");
        };
        assert_eq!(timeout, Duration::from_secs(60));
    }

    #[test]
    fn rejects_bad_limits() {
        for bad in ["0", "-1", "soon", "inf", "NaN"] {
            assert!(
                Cli::try_parse_from(["p", "run", "--timeout", bad]).is_err(),
                "{bad}"
            );
            assert!(
                Cli::try_parse_from(["p", "ready", "--timeout", bad]).is_err(),
                "{bad}"
            );
        }
    }
}
