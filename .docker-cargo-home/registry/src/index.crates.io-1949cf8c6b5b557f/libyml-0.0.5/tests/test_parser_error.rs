//! This module contains tests for the YAML parser error handling.
//! It ensures that the parser correctly identifies and reports errors in invalid YAML documents.

#![allow(clippy::type_complexity, clippy::uninlined_format_args)]

use std::io::{Read, Write};
use std::path::Path;

mod bin;
#[path = "../src/bin/run-parser-test-suite.rs"]
#[allow(dead_code)]
mod run_parser_test_suite;

/// Wrapper function to bridge the error types between the test suite and the parser.
///
/// This function wraps the `unsafe_main` function from the parser test suite,
/// converting its `anyhow::Error` into the `bin::MyError` expected by the test runner.
///
/// # Safety
///
/// This function is unsafe because it calls an unsafe function `unsafe_main`.
/// The caller must ensure that the provided `stdin` and `stdout` are valid for the lifetime of the call.
///
/// # Arguments
///
/// * `stdin` - A mutable reference to a type that implements `Read`
/// * `stdout` - A mutable reference to a type that implements `Write`
///
/// # Returns
///
/// Returns `Ok(())` if parsing succeeds, or `Err(bin::MyError)` if an error occurs.
unsafe fn unsafe_main_wrapper(
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
) -> Result<(), bin::MyError> {
    run_parser_test_suite::unsafe_main(stdin, stdout)
        .map_err(|e| bin::MyError::Other(e.to_string()))
}

/// Runs a single parser error test case.
///
/// This function sets up the test environment, runs the parser on the input file,
/// and checks that the parser fails as expected for invalid YAML.
///
/// # Arguments
///
/// * `id` - A string slice that holds the identifier for the test case
///
/// # Panics
///
/// This function will panic if the parser succeeds on an input that should fail.
fn test(id: &str) {
    let dir = Path::new("tests")
        .join("data")
        .join("yaml-test-suite")
        .join(id);

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &dir.join("in.yaml"),
    );

    if output.success {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{}", stdout);
        eprint!("{}", stderr);
        panic!("expected parse to fail");
    }
}

// Run the test suite for parser errors
libyml_test_suite::test_parser_error!();
