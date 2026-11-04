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
//! It has one subcommand so far: `list [FILTER]...` prints each test's name
//! and description.
//!
//! Any other arguments are libtest's, so the program also works as a
//! `harness = false` test target under `cargo test` and nextest: it answers
//! `--list --format terse`, `--ignored`, and `<name> --exact --nocapture`.
//! In that mode tests run in the program's own process, one at a time unless
//! `--test-threads` says otherwise.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::registry::{RESERVED_NAMES, Selection, TESTS, Test, validate};

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
}

fn command(_program: &str, tests: &'static [Test], command: Command) -> ExitCode {
    match command {
        Command::List { filters } => {
            list(tests, filters);
            ExitCode::SUCCESS
        }
    }
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
    use super::Cli;

    #[test]
    fn cli_is_consistent() {
        <Cli as clap::CommandFactory>::command().debug_assert();
    }
}
